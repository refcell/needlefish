//! Real L1 data path for the simulator. The batcher model encodes L2 blocks with the
//! batcher lane's channel manager (singular batches, zlib, frame tx data); L1 carries
//! opaque tx data; verifiers decode it with the consensus protocol codecs (frames,
//! channel assembly, decompression, batch reader, singular batch decoding).
//!
//! Verifiers read each L1 block through the derive lane's retrieval (calldata source,
//! inbox and batcher sender filter) and frame queue, via `BlockProvider`.
//!
//! Every submission is one channel in one frame, so decoding is stateless per L1
//! transaction and L1 reorg handling stays in the follower. Multi-frame channels across
//! L1 blocks need a channel bank; the simulator adopts the derive lane's once it lands.
//!
//! Model block encoding: block `n` is a singular batch with `timestamp = n * 2`,
//! `parent_hash` / hash carrying the model's 64-bit hashes, and one EIP-1559
//! transaction whose 8-byte input is the payload (`payload_tx`).

const std = @import("std");
const assert = std.debug.assert;
const manager_module = @import("../../batcher/channel/manager.zig");
const source = @import("../../batcher/source/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const tx_module = @import("../../common/consensus/tx.zig");

const derive = @import("../../consensus/derive/root.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const BlockInfo = protocol.BlockInfo;
const L1Transaction = derive.providers.L1Transaction;
const ProviderError = derive.errors.ProviderError;
const SingleBatch = protocol.batch.SingleBatch;
const batch_reader = protocol.batch_reader;

/// Blocks one decoded channel may carry (the real batcher packs more than the model).
pub const blocks_max = 16;
/// Encoded length of `payload_tx`, which holds one L2 block's payload.
pub const payload_tx_length_max = 128;
pub const l2_chain_id = 901;
/// Largest tx data: version byte plus one frame.
pub const tx_data_max = 2048;
pub const l2_block_time_s = 2;
pub const l1_block_time_s = 12;
const frame_size_max = tx_data_max - 1;
const input_bytes_max = 4096;
const decompressed_bytes_max = 16 * 1024;
const scratch_bytes = 256 * 1024;
const pipeline_scratch_bytes = 64 * 1024;
/// Batcher transactions per L1 block the provider exposes.
pub const transactions_max = 8;

/// L1 senders: the authorized batcher, and an attacker posting well-formed channels to
/// the inbox. Derivation must only accept the batcher's.
pub const sender_batcher: u8 = 0;
pub const sender_attacker: u8 = 1;
pub const batch_inbox = Address.init(@splat(0xff));

pub fn sender_address(sender: u8) Address {
    return Address.init(@splat(0xb0 | sender));
}

pub const rollup: protocol.RollupConfig = .{ .batch_inbox_address = batch_inbox };

/// A contiguous run of L2 blocks recovered from one L1 transaction.
pub const Blocks = struct {
    number_first: u64,
    count: u8,
    payloads: [blocks_max]u64,
};

/// The model's L2 transaction for a block: a fixed EIP-1559 transfer whose input is the
/// payload. Signature values are placeholders; nothing recovers the sender.
pub fn payload_envelope(payload: *const [8]u8) tx_module.Envelope {
    return .{ .eip1559 = .{
        .tx = .{
            .chain_id = l2_chain_id,
            .nonce = 0,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 2,
            .gas_limit = 21_000,
            .to = .{ .call = .{ .bytes = @splat(0x11) } },
            .value = 0,
            .input = payload,
            .access_list = .empty,
        },
        .signature = .{ .y_parity = false, .r = 1, .s = 1 },
    } };
}

pub fn payload_tx(payload: u64, out: *[payload_tx_length_max]u8) []u8 {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, payload, .big);
    const encoded = payload_envelope(&bytes).encode_to(out);
    assert(encoded.len <= payload_tx_length_max);
    return encoded;
}

fn payload_from_tx(encoded: []const u8) ?u64 {
    const envelope = tx_module.Envelope.decode(encoded) catch return null;
    const tx = switch (envelope) {
        .eip1559 => |signed| signed.tx,
        else => return null,
    };
    if (tx.input.len != 8) return null;
    return std.mem.readInt(u64, tx.input[0..8], .big);
}

pub fn word_hash(word: u64) B256 {
    var hash: B256 = .zero;
    std.mem.writeInt(u64, hash.bytes[24..32], word, .big);
    return hash;
}

/// Append-only store of submitted tx data. L1 blocks reference entries by index, as
/// real blocks carry transactions; entries are never rewritten, so a stale message
/// about an orphaned L1 block still names the same bytes.
pub const TxPool = struct {
    bytes: []u8,
    lengths: []u16,
    count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, entries_max: u32) !TxPool {
        assert(entries_max > 0);
        const bytes = try allocator.alloc(u8, @as(usize, entries_max) * tx_data_max);
        errdefer allocator.free(bytes);
        const lengths = try allocator.alloc(u16, entries_max);
        return .{ .bytes = bytes, .lengths = lengths };
    }

    pub fn deinit(pool: *TxPool, allocator: std.mem.Allocator) void {
        allocator.free(pool.bytes);
        allocator.free(pool.lengths);
        pool.* = undefined;
    }

    /// Stores `data`; returns its index, or null when the pool is full.
    pub fn append(pool: *TxPool, data: []const u8) ?u32 {
        assert(data.len > 0 and data.len <= tx_data_max);
        if (pool.count == pool.lengths.len) return null;
        const index = pool.count;
        @memcpy(pool.bytes[@as(usize, index) * tx_data_max ..][0..data.len], data);
        pool.lengths[index] = @intCast(data.len);
        pool.count += 1;
        return index;
    }

    pub fn get(pool: *const TxPool, index: u32) []const u8 {
        assert(index < pool.count);
        return pool.bytes[@as(usize, index) * tx_data_max ..][0..pool.lengths[index]];
    }

    /// Mutable view for byzantine tests that corrupt data already on L1.
    pub fn get_mutable(pool: *TxPool, index: u32) []u8 {
        assert(index < pool.count);
        return pool.bytes[@as(usize, index) * tx_data_max ..][0..pool.lengths[index]];
    }
};

pub const Encoder = struct {
    manager: manager_module.Manager,

    pub fn init(allocator: std.mem.Allocator, seed: u64) !Encoder {
        var channel_id_seed: [16]u8 = @splat(0);
        std.mem.writeInt(u64, channel_id_seed[0..8], seed, .big);
        const manager = try manager_module.Manager.init(allocator, .{
            .channel = .{ .frame_size_max = frame_size_max, .input_bytes_max = input_bytes_max },
            .batch_bytes_max = 512,
        }, channel_id_seed);
        return .{ .manager = manager };
    }

    pub fn deinit(encoder: *Encoder, allocator: std.mem.Allocator) void {
        encoder.manager.deinit(allocator);
        encoder.* = undefined;
    }

    /// Encodes `payloads.len` blocks starting at `first` as one single-frame channel.
    /// `hashes[i]` is the hash of block `first - 1 + i` (so it starts at the parent).
    /// The result borrows the encoder and is valid until the next call.
    pub fn encode(
        encoder: *Encoder,
        first: u64,
        hashes: []const u64,
        payloads: []const u64,
    ) []const u8 {
        assert(first > 0 and payloads.len > 0 and payloads.len <= blocks_max);
        assert(hashes.len == payloads.len + 1);
        const manager = &encoder.manager;
        manager.reset();
        for (payloads, 0..) |payload, offset| {
            const number = first + offset;
            var transaction_buffer: [payload_tx_length_max]u8 = undefined;
            const transactions = [_][]const u8{payload_tx(payload, &transaction_buffer)};
            const block: source.L2Block = .{
                .number = number,
                .hash = word_hash(hashes[offset + 1]),
                .parent_hash = word_hash(hashes[offset]),
                .timestamp = number * l2_block_time_s,
                .l1_origin = .{},
                .sequence_number = 0,
                .transactions = &transactions,
            };
            // Proof: the channel input target (~3 KiB) exceeds blocks_max batches (~90 B).
            manager.add_block(&block, 0) catch unreachable;
        }
        manager.close_open();
        const data = manager.next_tx_data() orelse unreachable; // Closed with batches.
        assert(!manager.has_pending_frames()); // One frame per channel.
        assert(data.len <= tx_data_max);
        return data;
    }
};

pub const Decoder = struct {
    /// Decompression allocates a full zlib window (64 KiB) plus the output.
    scratch: []u8,

    pub fn init(allocator: std.mem.Allocator) !Decoder {
        return .{ .scratch = try allocator.alloc(u8, scratch_bytes) };
    }

    pub fn deinit(decoder: *Decoder, allocator: std.mem.Allocator) void {
        allocator.free(decoder.scratch);
        decoder.* = undefined;
    }

    /// Decodes one L1 transaction, or null when it is not a valid single-frame channel
    /// of contiguous model blocks (derivation then ignores it).
    pub fn decode(decoder: *Decoder, tx_data: []const u8) ?Blocks {
        var frames_buffer: [4]protocol.Frame = undefined;
        const frames = protocol.frame.parse_frames(tx_data, &frames_buffer) catch return null;
        assert(frames.len > 0);
        if (frames.len != 1) return null;
        return decoder.decode_frame(frames[0]);
    }

    /// Decodes a frame that must be a complete channel on its own.
    pub fn decode_frame(decoder: *Decoder, frame: protocol.Frame) ?Blocks {
        var fixed = std.heap.FixedBufferAllocator.init(decoder.scratch);
        const allocator = fixed.allocator();
        var channel = protocol.Channel.init(frame.id, .{});
        channel.add_frame(allocator, frame, .{}) catch return null;
        if (!channel.is_ready()) return null;
        const data = channel.frame_data_alloc(allocator) catch return null;
        const decompressed = batch_reader.decompress_channel(
            allocator,
            data,
            decompressed_bytes_max,
            false,
        ) catch return null;
        return decode_batches(allocator, decompressed);
    }
};

/// Chain provider (see `consensus/derive/providers.zig`) over the one L1 block a node is
/// processing: the real derive stages read it as they would an L1 RPC.
pub const BlockProvider = struct {
    info: BlockInfo,
    transactions: [transactions_max]L1Transaction,
    transaction_count: u8,

    pub fn init(
        number: u64,
        hash: u64,
        parent_hash: u64,
        pool: *const TxPool,
        tx_indexes: []const u32,
        senders: []const u8,
        sender_check: bool,
    ) BlockProvider {
        assert(tx_indexes.len == senders.len and tx_indexes.len <= transactions_max);
        var provider: BlockProvider = .{
            .info = .{
                .hash = word_hash(hash),
                .number = number,
                .parent_hash = word_hash(parent_hash),
                .timestamp = number * l1_block_time_s,
            },
            .transactions = undefined,
            .transaction_count = @intCast(tx_indexes.len),
        };
        for (tx_indexes, senders, 0..) |tx_index, sender, index| {
            provider.transactions[index] = .{
                .tx_type = L1Transaction.type_eip1559,
                .to = batch_inbox,
                // A disabled sender check is modelled as every sender looking authorized.
                .from = sender_address(if (sender_check) sender else sender_batcher),
                .input = pool.get(tx_index),
            };
        }
        return provider;
    }

    pub fn l1_block_info_by_number(provider: *BlockProvider, number: u64) ProviderError!BlockInfo {
        if (number != provider.info.number) return error.NotFound;
        return provider.info;
    }

    pub fn l1_receipts_by_hash(
        provider: *BlockProvider,
        hash: B256,
    ) ProviderError![]const protocol.log.Receipt {
        if (!hash.eql(provider.info.hash)) return error.NotFound;
        return &.{};
    }

    pub fn l1_transactions_by_hash(
        provider: *BlockProvider,
        hash: B256,
    ) ProviderError![]const L1Transaction {
        if (!hash.eql(provider.info.hash)) return error.NotFound;
        return provider.transactions[0..provider.transaction_count];
    }

    pub fn blobs(
        _: *BlockProvider,
        _: BlockInfo,
        _: []const B256,
    ) ProviderError![]const *const derive.blob.Blob {
        return error.BlobsUnavailable; // The model rollup never activates blobs.
    }
};

pub const Derived = struct {
    blocks: [transactions_max]Blocks = undefined,
    count: u8 = 0,
    /// Frames from the authorized batcher that failed to decode.
    invalid: u8 = 0,
};

/// Runs the derive lane's L1 retrieval and frame queue over one L1 block, then decodes
/// each single-frame channel. Only the batcher's transactions to the inbox survive the
/// data source filter.
pub fn derive_l1_block(decoder: *Decoder, provider: *BlockProvider) Derived {
    var pipeline_memory: [pipeline_scratch_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&pipeline_memory);
    const allocator = fixed.allocator();
    var retrieval = derive.retrieval.Retrieval.init(allocator, &rollup);
    var queue = derive.frame_queue.FrameQueue.init(allocator, &rollup);
    const system_config: protocol.SystemConfig = .{
        .batcher_address = sender_address(sender_batcher),
    };
    // Proof: the provider serves exactly this block, and the scratch fits its data.
    retrieval.reset(provider, provider.info.id(), system_config) catch unreachable;
    var derived: Derived = .{};
    for (0..transactions_max * 4 + 2) |_| {
        const frame = queue.next_frame(&retrieval, provider, provider) catch |err| switch (err) {
            error.Eof => break,
            error.NotEnoughData => {
                derived.invalid += 1; // A batcher payload that held no valid frame.
                continue;
            },
            else => unreachable, // Proof: provider errors are impossible for this block.
        };
        if (decoder.decode_frame(frame)) |blocks| {
            assert(derived.count < transactions_max);
            derived.blocks[derived.count] = blocks;
            derived.count += 1;
        } else {
            derived.invalid += 1;
        }
    } else unreachable; // Proof: at most transactions_max payloads of one frame each.
    assert(derived.count + derived.invalid <= transactions_max * 4);
    return derived;
}

fn decode_batches(allocator: std.mem.Allocator, decompressed: []const u8) ?Blocks {
    var reader = batch_reader.BatchReader.init(decompressed);
    var blocks: Blocks = .{ .number_first = 0, .count = 0, .payloads = undefined };
    for (0..blocks_max + 1) |_| {
        const raw = (reader.next() catch return null) orelse break;
        if (raw.batch_type != .single) return null;
        if (blocks.count == blocks_max) return null;
        const batch = SingleBatch.decode(allocator, raw.payload) catch return null;
        if (batch.transactions.len != 1) return null;
        const payload = payload_from_tx(batch.transactions[0]) orelse return null;
        if (batch.timestamp == 0 or batch.timestamp % l2_block_time_s != 0) return null;
        const number = batch.timestamp / l2_block_time_s;
        if (blocks.count == 0) {
            blocks.number_first = number;
        } else if (number != blocks.number_first + blocks.count) {
            return null;
        }
        blocks.payloads[blocks.count] = payload;
        blocks.count += 1;
    } else return null; // More than blocks_max batches.
    if (blocks.count == 0) return null;
    assert(blocks.number_first > 0);
    return blocks;
}

const testing = std.testing;
const fuzz = @import("../fuzz.zig");

const Fixture = struct {
    hashes: [blocks_max + 2]u64,
    payloads: [blocks_max + 2]u64,
    encoder: Encoder,
    decoder: Decoder,

    fn init(fixture: *Fixture, seed: u64) !void {
        var prng = @import("../prng.zig").Prng.init(seed);
        for (&fixture.hashes, &fixture.payloads) |*hash, *payload| {
            hash.* = prng.int(u64);
            payload.* = prng.int(u64);
        }
        fixture.encoder = try Encoder.init(testing.allocator, seed);
        errdefer fixture.encoder.deinit(testing.allocator);
        fixture.decoder = try Decoder.init(testing.allocator);
    }

    fn deinit(fixture: *Fixture) void {
        fixture.encoder.deinit(testing.allocator);
        fixture.decoder.deinit(testing.allocator);
    }
};

test "codec: encode then decode round trips every batch size" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    var count: u8 = 1;
    while (count <= blocks_max) : (count += 1) {
        const data = fixture.encoder.encode(
            1,
            fixture.hashes[0 .. count + 1],
            fixture.payloads[1..][0..count],
        );
        const blocks = fixture.decoder.decode(data) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(@as(u64, 1), blocks.number_first);
        try testing.expectEqual(count, blocks.count);
        const expected = fixture.payloads[1..][0..count];
        try testing.expectEqualSlices(u64, expected, blocks.payloads[0..count]);
    }
}

fn fuzz_tamper(fixture: *Fixture, smith: *std.testing.Smith) anyerror!void {
    const count: u8 = smith.valueRangeAtMost(u8, 1, blocks_max);
    const first: u64 = smith.valueRangeAtMost(u8, 1, blocks_max + 1 - count);
    const encoded = fixture.encoder.encode(
        first,
        fixture.hashes[first - 1 ..][0 .. count + 1],
        fixture.payloads[first..][0..count],
    );
    var data: [tx_data_max]u8 = undefined;
    @memcpy(data[0..encoded.len], encoded);
    var length: u32 = @intCast(encoded.len);
    if (smith.value(bool)) length = smith.valueRangeAtMost(u32, 1, length);
    const flips = smith.valueRangeAtMost(u8, 0, 3);
    for (0..flips) |_| data[smith.index(length)] ^= smith.value(u8) | 1;
    // Tampered tx data either fails to decode or decodes to a well-formed run.
    // (zlib's Adler-32 makes a silently different payload astronomically unlikely, but
    // the derivation model must not rely on it: it only needs a contiguous run.)
    const blocks = fixture.decoder.decode(data[0..length]) orelse return;
    try testing.expect(blocks.count >= 1 and blocks.count <= blocks_max);
    try testing.expect(blocks.number_first > 0);
    if (flips == 0 and length == encoded.len) {
        try testing.expectEqual(first, blocks.number_first);
        const expected = fixture.payloads[first..][0..count];
        try testing.expectEqualSlices(u64, expected, blocks.payloads[0..count]);
    }
}

test "codec: tampered tx data never decodes to a malformed run" {
    var fixture: Fixture = undefined;
    try fixture.init(2);
    defer fixture.deinit();
    try fuzz.run(&fixture, fuzz_tamper, .{ .iterations = 256 });
}

test "codec: pool keeps entries stable and reports full" {
    var pool = try TxPool.init(testing.allocator, 2);
    defer pool.deinit(testing.allocator);
    try testing.expectEqual(@as(?u32, 0), pool.append("ab"));
    try testing.expectEqual(@as(?u32, 1), pool.append("cde"));
    try testing.expectEqual(@as(?u32, null), pool.append("f"));
    try testing.expectEqualStrings("ab", pool.get(0));
    try testing.expectEqualStrings("cde", pool.get(1));
}

test "codec: derive stages keep the batcher's channel and drop an attacker's" {
    var fixture: Fixture = undefined;
    try fixture.init(3);
    defer fixture.deinit();
    var pool = try TxPool.init(testing.allocator, 4);
    defer pool.deinit(testing.allocator);
    const honest = fixture.encoder.encode(1, fixture.hashes[0..3], fixture.payloads[1..3]);
    const honest_index = pool.append(honest).?;
    var forged_payloads = fixture.payloads;
    for (&forged_payloads) |*payload| payload.* +%= 1;
    const forged = fixture.encoder.encode(1, fixture.hashes[0..3], forged_payloads[1..3]);
    const forged_index = pool.append(forged).?;
    // Order the attacker first: it must not shadow or displace the batcher's data.
    const indexes = [_]u32{ forged_index, honest_index };
    const senders = [_]u8{ sender_attacker, sender_batcher };
    var provider = BlockProvider.init(5, 0xaa, 0xbb, &pool, &indexes, &senders, true);
    const derived = derive_l1_block(&fixture.decoder, &provider);
    try testing.expectEqual(@as(u8, 1), derived.count);
    try testing.expectEqual(@as(u8, 0), derived.invalid);
    try testing.expectEqualSlices(u64, fixture.payloads[1..3], derived.blocks[0].payloads[0..2]);
}

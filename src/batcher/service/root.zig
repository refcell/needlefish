//! Batcher service: one `step` polls L1, the rollup node and the L2 EL, loads new
//! unsafe L2 blocks into channels, hands frames to the transaction manager, and
//! tracks inclusion. The caller drives `step` on a timer; all IO goes through the
//! injected RPC clients, so the simulator can run the service deterministically.
//!
//! Safe-head handling follows op-batcher: blocks load from `safe_l2 + 1` on start or
//! after a reset, and a safe head that overtakes our loaded range (another batcher,
//! or a restart) resets the channel state. Without a rollup node (`optimism_syncStatus`
//! unavailable) the L2 EL head is used as the unsafe head and the safe head is 0.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");
const source = @import("../source/root.zig");
const channel_manager = @import("../channel/manager.zig");
const throttle = @import("../throttle/root.zig");
const txmgr = @import("../txmgr/root.zig");
const primitives = @import("../../common/primitives/root.zig");

pub const Config = struct {
    channels: channel_manager.Config,
    txs: txmgr.Config,
    source: source.Limits = .{},
    blocks_per_step_max: u32 = 64,
    /// Reset and resubmit from the safe head when it has not advanced for this many L1
    /// blocks while we hold later blocks (lost or timed-out channels). 0 disables it;
    /// it needs a rollup node.
    stall_l1_blocks: u64 = 0,
    /// DA throttling of the L2 block builder (`miner_setMaxDASize`); off by default here,
    /// `base batcher` enables it like base/base.
    throttle: throttle.Config = .{ .strategy = .off },
};

pub const Clients = struct {
    l1: *rpc.Client,
    l2: *rpc.Client,
    /// Rollup node; null runs without safe-head tracking.
    rollup: ?*rpc.Client,
};

pub const Heads = struct {
    l1: u64,
    safe_l2: u64,
    unsafe_l2: u64,
    /// False when no rollup node answered and `safe_l2` is a placeholder 0.
    safe_known: bool = false,
};

pub const Report = struct {
    heads: Heads = .{ .l1 = 0, .safe_l2 = 0, .unsafe_l2 = 0 },
    blocks_loaded: u32 = 0,
    txs_submitted: u32 = 0,
    txs_confirmed: u32 = 0,
    resets: u32 = 0,
    da_backlog_bytes: u64 = 0,
    throttle: throttle.Outcome = .idle,
};

pub const Error = rpc.Error || source.Error || txmgr.Error;

pub const Service = struct {
    channels: channel_manager.Manager,
    txs: txmgr.TxManager,
    decoder: source.Decoder,
    blocks_per_step_max: u32,
    stall_l1_blocks: u64,
    /// Highest safe head seen and the L1 head when it was first seen.
    safe_seen: u64,
    safe_seen_at_l1: u64,
    throttle: throttle.Throttle,
    backlog: throttle.BacklogEstimate,

    pub fn init(allocator: std.mem.Allocator, config: Config, channel_id_seed: [16]u8) !Service {
        assert(config.blocks_per_step_max > 0);
        const Manager = channel_manager.Manager;
        var channels = try Manager.init(allocator, config.channels, channel_id_seed);
        errdefer channels.deinit(allocator);
        var txs = try txmgr.TxManager.init(allocator, config.txs);
        errdefer txs.deinit(allocator);
        const decoder = try source.Decoder.init(allocator, config.source);
        return .{
            .channels = channels,
            .txs = txs,
            .decoder = decoder,
            .blocks_per_step_max = config.blocks_per_step_max,
            .stall_l1_blocks = config.stall_l1_blocks,
            .safe_seen = 0,
            .safe_seen_at_l1 = 0,
            .throttle = .init(config.throttle),
            .backlog = .{},
        };
    }

    pub fn deinit(service: *Service, allocator: std.mem.Allocator) void {
        service.channels.deinit(allocator);
        service.txs.deinit(allocator);
        service.decoder.deinit(allocator);
        service.* = undefined;
    }

    pub fn step(service: *Service, clients: Clients, now_ms: u64) Error!Report {
        var report: Report = .{};
        report.heads = try read_heads(clients);
        service.channels.on_l1_head(report.heads.l1);
        if (report.heads.safe_known) service.watch_safe_head(report.heads, &report);
        try service.load_blocks(clients, report.heads, &report);
        report.da_backlog_bytes = service.backlog.backlog_bytes(
            report.heads.unsafe_l2,
            report.heads.safe_l2,
        );
        report.throttle = service.throttle.update(clients.l2, report.da_backlog_bytes, now_ms);
        try service.submit_frames(clients.l1, now_ms, &report);
        report.txs_confirmed = try service.txs.poll(clients.l1, now_ms);
        assert(report.txs_submitted <= service.txs.slots.len);
        return report;
    }

    /// Resets when the safe head stalls behind blocks we already loaded.
    fn watch_safe_head(service: *Service, heads: Heads, report: *Report) void {
        if (heads.safe_l2 > service.safe_seen or service.safe_seen_at_l1 == 0) {
            service.safe_seen = @max(service.safe_seen, heads.safe_l2);
            service.safe_seen_at_l1 = heads.l1;
            return;
        }
        if (service.stall_l1_blocks == 0) return;
        const next = service.channels.next_block_number() orelse return;
        if (next <= heads.safe_l2 + 1) return;
        if (heads.l1 < service.safe_seen_at_l1 + service.stall_l1_blocks) return;
        service.channels.reset();
        service.safe_seen_at_l1 = heads.l1;
        report.resets += 1;
        assert(service.channels.next_block_number() == null);
    }

    fn load_blocks(service: *Service, clients: Clients, heads: Heads, report: *Report) Error!void {
        if (service.channels.next_block_number()) |next| {
            if (next <= heads.safe_l2) {
                service.channels.reset();
                report.resets += 1;
            }
        }
        var next = service.channels.next_block_number() orelse heads.safe_l2 + 1;
        while (next <= heads.unsafe_l2 and report.blocks_loaded < service.blocks_per_step_max) {
            var params: [48]u8 = undefined;
            const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{next}) catch
                unreachable; // A u64 quantity fits.
            const block = try service.decoder.decode(try clients.l2.call(
                "eth_getBlockByNumber",
                text,
            ));
            if (block.number != next) return error.MalformedResponse;
            service.channels.add_block(&block, heads.l1) catch |err| switch (err) {
                error.Backpressure => return,
                error.Reorg => {
                    service.channels.reset();
                    report.resets += 1;
                    return;
                },
                error.BatchTooLarge => return error.BlockTooLarge,
            };
            service.backlog.observe_block(throttle.block_da_bytes(block.transactions));
            report.blocks_loaded += 1;
            next += 1;
        }
    }

    fn submit_frames(service: *Service, l1: *rpc.Client, now_ms: u64, report: *Report) Error!void {
        const frames: txmgr.FrameSource = .{ .context = &service.channels, .next_fn = next_frame };
        while (service.txs.has_capacity() and service.channels.has_pending_frames()) {
            // Nonce and fees are read before frames are pulled, so an error here leaves
            // the frames in the channel manager; a slot that exists is resent by poll.
            if (!try service.txs.submit_from(l1, frames, now_ms)) return;
            report.txs_submitted += 1;
        }
    }

    fn next_frame(context: *anyopaque) ?[]const u8 {
        const channels: *channel_manager.Manager = @ptrCast(@alignCast(context));
        return channels.next_tx_data();
    }
};

/// The rollup.json fields the batcher needs (op-node JSON schema).
pub const RollupFields = struct {
    l1_chain_id: u64,
    batch_inbox_address: primitives.Address,

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) !RollupFields {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
        defer parsed.deinit();
        const chain_id = try rpc.field(parsed.value, "l1_chain_id");
        const inbox = try rpc.field(parsed.value, "batch_inbox_address");
        const fields: RollupFields = .{
            .l1_chain_id = try rpc.number(chain_id),
            .batch_inbox_address = .{ .bytes = try rpc.fixed(20, inbox) },
        };
        if (fields.l1_chain_id == 0) return error.MalformedResponse;
        return fields;
    }
};

fn read_heads(clients: Clients) Error!Heads {
    const l1 = try rpc.quantity(u64, try clients.l1.call("eth_blockNumber", "[]"));
    if (clients.rollup) |rollup| {
        if (rollup.call("optimism_syncStatus", "[]")) |status| {
            const safe = try rpc.field(status, "safe_l2");
            const unsafe = try rpc.field(status, "unsafe_l2");
            return .{
                .l1 = l1,
                .safe_l2 = try rpc.number(try rpc.field(safe, "number")),
                .unsafe_l2 = try rpc.number(try rpc.field(unsafe, "number")),
                .safe_known = true,
            };
        } else |_| {}
    }
    const unsafe = try rpc.quantity(u64, try clients.l2.call("eth_blockNumber", "[]"));
    return .{ .l1 = l1, .safe_l2 = 0, .unsafe_l2 = unsafe };
}

const testing = std.testing;
const consensus = @import("../../common/consensus/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const frame_module = @import("../frame/root.zig");
const comp = @import("../comp/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const batch_module = @import("../../consensus/protocol/batch.zig");
const l1_info = @import("../../consensus/protocol/l1_info.zig");
const accounts = @import("../devnet/accounts.zig");

/// In-memory L1 and L2 behind the JSON-RPC transport interface. L1 mines every
/// sent transaction immediately; L2 serves `l2_head` empty blocks.
const FakeChains = struct {
    l1_head: u64 = 100,
    l2_head: u64 = 0,
    safe_l2: u64 = 0,
    mined_nonce: u64 = 0,
    sent: [16][4096]u8 = undefined,
    sent_lengths: [16]usize = @splat(0),
    sent_count: usize = 0,
    info_hex: [2 * l1_info.calldata_length_max]u8 = undefined,
    info_hex_length: usize = 0,
    /// `miner_setMaxDASize` calls on L2: the last pushed max block size.
    da_limit_pushes: u32 = 0,
    da_max_block_size: u64 = 0,

    const Role = struct { chains: *FakeChains, is_l1: bool };

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const role: *Role = @ptrCast(@alignCast(context));
        const id = between(body, "\"id\":", ",");
        const method = between(body, "\"method\":\"", "\"");
        var result_buffer: [1024]u8 = undefined;
        const result = role.chains.answer(role.is_l1, method, body, &result_buffer) catch
            return error.ResponseTooLarge;
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, result }) catch
            return error.ResponseTooLarge;
        return text.len;
    }

    fn between(body: []const u8, start: []const u8, end: []const u8) []const u8 {
        const from = std.mem.indexOf(u8, body, start).? + start.len;
        const length = std.mem.indexOf(u8, body[from..], end).?;
        return body[from..][0..length];
    }

    fn answer(
        chains: *FakeChains,
        is_l1: bool,
        method: []const u8,
        body: []const u8,
        out: []u8,
    ) ![]const u8 {
        const eql = std.mem.eql;
        if (eql(u8, method, "eth_blockNumber")) {
            const head = if (is_l1) chains.l1_head else chains.l2_head;
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{head});
        }
        if (eql(u8, method, "eth_getTransactionCount")) {
            return std.fmt.bufPrint(out, "\"0x{x}\"", .{chains.mined_nonce});
        }
        if (eql(u8, method, "eth_maxPriorityFeePerGas")) return "\"0x1\"";
        if (eql(u8, method, "optimism_syncStatus")) {
            return std.fmt.bufPrint(out, "{{\"safe_l2\":{{\"number\":{d}}}," ++
                "\"unsafe_l2\":{{\"number\":{d}}}}}", .{ chains.safe_l2, chains.l2_head });
        }
        if (eql(u8, method, "eth_sendRawTransaction")) {
            const raw_hex = between(body, "\"params\":[\"0x", "\"");
            const slot = &chains.sent[chains.sent_count];
            const raw = try primitives.hex.decode_into(slot, raw_hex);
            chains.sent_lengths[chains.sent_count] = raw.len;
            chains.sent_count += 1;
            chains.mined_nonce += 1;
            return "\"0x00\"";
        }
        if (eql(u8, method, "miner_setMaxDASize")) {
            assert(!is_l1);
            const params = between(body, "\"params\":[", "]");
            const block_hex = between(params, ",\"", "\"");
            chains.da_max_block_size = try primitives.hex.decode_quantity(u64, block_hex);
            chains.da_limit_pushes += 1;
            return "true";
        }
        assert(eql(u8, method, "eth_getBlockByNumber"));
        if (is_l1) return "{\"baseFeePerGas\":\"0x7\"}";
        const number_hex = between(body, "\"params\":[\"", "\"");
        const number = try primitives.hex.decode_quantity(u64, number_hex);
        return std.fmt.bufPrint(out, "{{\"number\":\"0x{x}\",\"hash\":\"0x{x:0>64}\"," ++
            "\"parentHash\":\"0x{x:0>64}\",\"timestamp\":\"0x{x}\",\"transactions\":" ++
            "[{{\"type\":\"0x7e\",\"input\":\"0x{s}\"}}]}}", .{
            number,
            number,
            number - 1,
            2 * number,
            chains.info_hex[0..chains.info_hex_length],
        });
    }
};

test "service: L2 blocks reach L1 as a complete channel of singular batches" {
    var chains: FakeChains = .{ .l2_head = 12 };
    const info: l1_info.L1BlockInfo = .{ .format = .jovian, .number = 90, .sequence_number = 0 };
    var calldata: [l1_info.calldata_length_max]u8 = undefined;
    const hex = std.fmt.bufPrint(&chains.info_hex, "{x}", .{info.encode_calldata(&calldata)}) catch
        unreachable;
    chains.info_hex_length = hex.len;
    var l1_role: FakeChains.Role = .{ .chains = &chains, .is_l1 = true };
    var l2_role: FakeChains.Role = .{ .chains = &chains, .is_l1 = false };
    const limits: rpc.Limits = .{ .response_bytes_max = 16384, .parse_bytes_max = 256 * 1024 };
    const l1_transport: rpc.Transport = .{ .context = &l1_role, .send_fn = FakeChains.send };
    const l2_transport: rpc.Transport = .{ .context = &l2_role, .send_fn = FakeChains.send };
    var l1 = try rpc.Client.init(testing.allocator, l1_transport, limits);
    defer l1.deinit(testing.allocator);
    var l2 = try rpc.Client.init(testing.allocator, l2_transport, limits);
    defer l2.deinit(testing.allocator);

    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var service = try Service.init(testing.allocator, .{
        .channels = .{
            .channel = .{
                .frame_size_max = 300,
                .target_frames = 16,
                .input_bytes_max = 64 * 1024,
            },
            .max_channel_duration_l1_blocks = 4,
            .batch_bytes_max = 4096,
        },
        .txs = .{
            .chain_id = 900,
            .private_key = batcher.private_key,
            .from = batcher.address,
            .to = .{ .bytes = @splat(0xff) },
            .tx_data_bytes_max = 1024,
        },
        .source = .{ .tx_count_max = 8, .tx_bytes_max = 4096, .input_bytes_max = 1024 },
        .blocks_per_step_max = 5,
        // A tiny threshold: 12 unsafe blocks over safe 0 (~70 bytes each) fully throttle.
        .throttle = .{ .start_threshold_bytes = 100, .full_threshold_bytes = 600 },
    }, @splat(3));
    defer service.deinit(testing.allocator);

    const clients: Clients = .{ .l1 = &l1, .l2 = &l2, .rollup = null };
    var loaded: u32 = 0;
    for (0..6) |round| {
        const report = try service.step(clients, round * 2000);
        loaded += report.blocks_loaded;
        try testing.expectEqual(@as(u64, 12 * 70), report.da_backlog_bytes);
        chains.l1_head += 1;
    }
    try testing.expectEqual(@as(u32, 12), loaded);
    // Steps at 0..10 s: pushed at 0 (new limits) and at 10 s (refresh), at full throttle.
    try testing.expectEqual(@as(u32, 2), chains.da_limit_pushes);
    try testing.expectEqual(@as(u64, 42_000), chains.da_max_block_size);
    try testing.expect(chains.sent_count > 0);
    try testing.expectEqual(@as(u32, 0), service.txs.pending_count());

    // Decode what reached L1: txs -> frames -> channel -> batches 1..12 in order.
    var bank: ?protocol.Channel = null;
    defer if (bank) |*channel| channel.deinit(testing.allocator);
    const sent_count = chains.sent_count;
    for (chains.sent[0..sent_count], chains.sent_lengths[0..sent_count]) |*raw, length| {
        const envelope = try consensus.Envelope.decode(raw[0..length]);
        const inbox: [20]u8 = @splat(0xff);
        try testing.expectEqualSlices(u8, &inbox, &envelope.eip1559.tx.to.call.bytes);
        var frames: [1]frame_module.Frame = undefined;
        const parsed = try frame_module.parse_frames(envelope.eip1559.tx.input, &frames);
        if (bank == null) bank = protocol.Channel.init(parsed[0].id, .{});
        try bank.?.add_frame(testing.allocator, parsed[0], .{ .number = 100 });
    }
    try testing.expect(bank.?.is_ready());
    const compressed = try bank.?.frame_data_alloc(testing.allocator);
    defer testing.allocator.free(compressed);
    const window = try testing.allocator.alloc(u8, std.compress.flate.max_window_len);
    defer testing.allocator.free(window);
    var plain: [16384]u8 = undefined;
    var decoder = rlp.Decoder.init(try comp.zlib_decompress(compressed, window, &plain));
    var number: u64 = 1;
    while (!decoder.is_empty()) : (number += 1) {
        const item = try decoder.bytes();
        var batch = try batch_module.SingleBatch.decode(testing.allocator, item[1..]);
        defer batch.deinit(testing.allocator);
        try testing.expectEqual(2 * number, batch.timestamp);
        try testing.expectEqual(@as(u64, 90), batch.epoch_num);
        try testing.expectEqual(@as(usize, 0), batch.transactions.len);
    }
    try testing.expectEqual(@as(u64, 13), number);
}

test "service: rollup fields from the devnet rollup.json" {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const genesis = @import("../devnet/genesis.zig");
    const anchor: genesis.GenesisAnchor = .{ .l1_hash = @splat(1), .l2_hash = @splat(2) };
    try genesis.write_rollup_config(&writer, &.{ .genesis_timestamp = 1_700_000_000 }, anchor);
    const fields = try RollupFields.parse(testing.allocator, writer.buffered());
    try testing.expectEqual(@as(u64, 900), fields.l1_chain_id);
    try testing.expectEqual(@as(u8, 0xff), fields.batch_inbox_address.bytes[0]);
    try testing.expectError(error.MalformedResponse, RollupFields.parse(testing.allocator, "{}"));
}

test "service: a stalled safe head triggers resubmission from safe + 1" {
    var chains: FakeChains = .{ .l2_head = 4 };
    const info: l1_info.L1BlockInfo = .{ .format = .jovian, .number = 90, .sequence_number = 0 };
    var calldata: [l1_info.calldata_length_max]u8 = undefined;
    const hex = std.fmt.bufPrint(&chains.info_hex, "{x}", .{info.encode_calldata(&calldata)}) catch
        unreachable;
    chains.info_hex_length = hex.len;
    var l1_role: FakeChains.Role = .{ .chains = &chains, .is_l1 = true };
    var l2_role: FakeChains.Role = .{ .chains = &chains, .is_l1 = false };
    const limits: rpc.Limits = .{ .response_bytes_max = 16384, .parse_bytes_max = 256 * 1024 };
    const l1_transport: rpc.Transport = .{ .context = &l1_role, .send_fn = FakeChains.send };
    const l2_transport: rpc.Transport = .{ .context = &l2_role, .send_fn = FakeChains.send };
    var l1 = try rpc.Client.init(testing.allocator, l1_transport, limits);
    defer l1.deinit(testing.allocator);
    var l2 = try rpc.Client.init(testing.allocator, l2_transport, limits);
    defer l2.deinit(testing.allocator);
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var service = try Service.init(testing.allocator, .{
        .channels = .{
            .channel = .{ .frame_size_max = 1000, .input_bytes_max = 64 * 1024 },
            .max_channel_duration_l1_blocks = 1,
            .batch_bytes_max = 4096,
        },
        .txs = .{
            .chain_id = 900,
            .private_key = batcher.private_key,
            .from = batcher.address,
            .to = .{ .bytes = @splat(0xff) },
            .tx_data_bytes_max = 1024,
        },
        .source = .{ .tx_count_max = 8, .tx_bytes_max = 4096, .input_bytes_max = 1024 },
        .stall_l1_blocks = 10,
    }, @splat(4));
    defer service.deinit(testing.allocator);
    const clients: Clients = .{ .l1 = &l1, .l2 = &l2, .rollup = &l2 };

    var resets: u32 = 0;
    var loaded: u32 = 0;
    for (0..12) |round| {
        const report = try service.step(clients, round * 2000);
        resets += report.resets;
        loaded += report.blocks_loaded;
        chains.l1_head += 1;
    }
    // Safe head never moved: one reset after 10 L1 blocks, and blocks 1..4 reloaded.
    try testing.expectEqual(@as(u32, 1), resets);
    try testing.expectEqual(@as(u32, 8), loaded);
    // Once the safe head advances there is no further reset.
    chains.safe_l2 = 4;
    for (12..30) |round| {
        const report = try service.step(clients, round * 2000);
        try testing.expectEqual(@as(u32, 0), report.resets);
        chains.l1_head += 1;
    }
}

//! Unsafe-block gossip handler: binds the gossipsub router to the four OP Stack block
//! topics of one chain, validates every received block (decode, signer, block hash,
//! version rules, seen-hash limits) before the router forwards it, queues accepted
//! blocks for consensus, and publishes blocks signed by the local sequencer.
//! Mirrors base/base `gossip/src/handler.rs` + `driver.rs` message handling.
//!
//! Memory is allocated once at `init`: one 10 MiB scratch buffer for snappy
//! decompression (message ids and validation take turns) and one buffer for publishing.
//! Accepted blocks are queued by message id; `pop_block` re-decodes the cached message
//! into a caller buffer, so a queued block costs 20 bytes, not a payload copy.

const std = @import("std");
const assert = std.debug.assert;
const router_module = @import("router.zig");
const block = @import("block.zig");
const validity = @import("validity.zig");
const snappy = @import("snappy.zig");
const score = @import("../peers/score.zig");
const primitives = @import("../../../common/primitives/root.zig");
const rollup_config = @import("../../protocol/rollup_config.zig");

pub const Router = router_module.Router;
pub const Id = router_module.Id;
pub const Slot = router_module.Slot;

const ns_per_s = std.time.ns_per_s;
const versions = [_]block.Version{ .v1, .v2, .v3, .v4 };
const accepted_max = 64;
/// Largest signed message we publish (base/base `MAX_GOSSIP_SIZE`).
const publish_size_max = snappy.gossip_size_max;

pub const Config = struct {
    rollup: *const rollup_config.RollupConfig,
    unsafe_block_signer: primitives.Address,
    /// L2 block time (seconds) for scoring parameters.
    block_time_s: u64 = 2,
    score_level: score.Level = .light,
    topic_scoring: bool = true,
    mcache: @import("mcache.zig").Config = .{},
    mesh: Mesh = .{},
};

/// Gossipsub mesh degrees (base/base `--p2p.gossip.mesh.*`).
pub const Mesh = struct {
    d: u32 = 8,
    d_low: u32 = 6,
    d_high: u32 = 12,
    d_lazy: u32 = 6,
};

pub const Stats = struct {
    accepted: u64 = 0,
    /// Validations that reused the message-id hash's decompression.
    decompress_reused: u64 = 0,
    rejected: u64 = 0,
    ignored: u64 = 0,
    accepted_dropped: u64 = 0,
    published: u64 = 0,
    /// Messages that did not decode as a payload envelope (rejected before validation).
    decode_failed: u64 = 0,
    /// Validation attempts per block version (base/base `block_version`).
    versions: [versions.len]u64 = @splat(0),
    /// Validation failures per reason (base/base `block_validation_failed`).
    failed: [std.meta.fieldNames(validity.Reason).len]u64 = @splat(0),
    /// Topics unsubscribed after their fork left the age window, per version.
    retirements: [versions.len]u64 = @splat(0),
    /// Local publishes refused because the version's topic is retired, per version.
    blocked_outbound: [versions.len]u64 = @splat(0),
};

pub const BlockGossip = struct {
    router: Router,
    validator: validity.Validator,
    chain_id: u64,
    /// Router topic index for each block version.
    topics: [versions.len]u8,
    scratch: []u8,
    /// The message whose decompressed bytes `scratch[0..scratch_length]` hold, so
    /// validation right after the message-id hash does not decompress it again.
    scratch_id: ?Id = null,
    scratch_length: u32 = 0,
    publish_scratch: []u8,
    publish_output: []u8,
    compressor: snappy.Compressor = .{},
    accepted: [accepted_max]Id = undefined,
    /// The payload hash validation computed for each queued id, so `pop_block` does
    /// not hash the payload a second time.
    accepted_hashes: [accepted_max]primitives.B256 = undefined,
    /// Set by `check` for the message it just accepted.
    checked_hash: primitives.B256 = undefined,
    accepted_head: u32 = 0,
    accepted_count: u32 = 0,
    stats: Stats = .{},

    /// Heap-allocates the handler: the router keeps a pointer to it for message ids.
    pub fn create(allocator: std.mem.Allocator, config: Config, random: std.Random) !*BlockGossip {
        assert(config.block_time_s > 0);
        const gossip = try allocator.create(BlockGossip);
        errdefer allocator.destroy(gossip);
        const scratch = try allocator.alloc(u8, snappy.gossip_size_max);
        errdefer allocator.free(scratch);
        const publish_scratch = try allocator.alloc(u8, publish_size_max);
        errdefer allocator.free(publish_scratch);
        const output_length: usize = @intCast(snappy.max_compressed_length(publish_size_max));
        const publish_output = try allocator.alloc(u8, output_length);
        errdefer allocator.free(publish_output);
        gossip.* = .{
            .router = undefined,
            .validator = .{
                .config = config.rollup,
                .unsafe_block_signer = config.unsafe_block_signer,
            },
            .chain_id = config.rollup.l2_chain_id,
            .topics = undefined,
            .scratch = scratch,
            .publish_scratch = publish_scratch,
            .publish_output = publish_output,
        };
        gossip.router = try Router.init(allocator, .{
            .message_id = message_id,
            .message_id_context = gossip,
            .d = config.mesh.d,
            .d_low = config.mesh.d_low,
            .d_high = config.mesh.d_high,
            .d_lazy = config.mesh.d_lazy,
            .d_score = @min(4, config.mesh.d),
            .d_out = @min(2, config.mesh.d / 2),
            .peer_params = score.peer_params(
                config.score_level,
                config.topic_scoring,
                config.block_time_s,
            ),
            .mcache = config.mcache,
        }, random);
        errdefer gossip.router.deinit(allocator);
        for (versions, 0..) |version, index| {
            var buffer: [block.topic_length_max]u8 = undefined;
            const name = block.topic(&buffer, gossip.chain_id, version);
            gossip.topics[index] = gossip.router.subscribe(name) catch unreachable; // 4 <= 8.
        }
        return gossip;
    }

    pub fn destroy(gossip: *BlockGossip, allocator: std.mem.Allocator) void {
        gossip.router.deinit(allocator);
        allocator.free(gossip.publish_output);
        allocator.free(gossip.publish_scratch);
        allocator.free(gossip.scratch);
        allocator.destroy(gossip);
    }

    fn message_id(context: ?*anyopaque, topic: []const u8, data: []const u8) Id {
        const gossip: *BlockGossip = @ptrCast(@alignCast(context.?));
        const result = block.message_id_and_bytes(topic, data, gossip.scratch);
        gossip.scratch_id = if (result.decompressed != null) result.id else null;
        gossip.scratch_length = if (result.decompressed) |bytes| @intCast(bytes.len) else 0;
        return result.id;
    }

    fn version_of(gossip: *const BlockGossip, topic: u8) block.Version {
        for (gossip.topics, 0..) |index, version| {
            if (index == topic) return versions[version];
        }
        unreachable; // The router only reports topics we subscribed.
    }

    /// The signer key changes through the L1 system config.
    pub fn set_unsafe_block_signer(gossip: *BlockGossip, signer: primitives.Address) void {
        gossip.validator.unsafe_block_signer = signer;
    }

    /// Feeds one inbound gossipsub RPC frame from `slot`, then validates the blocks it
    /// carried so valid ones are forwarded before this returns.
    pub fn on_rpc(
        gossip: *BlockGossip,
        slot: Slot,
        frame: []const u8,
        now_ns: u64,
    ) Router.RpcError!void {
        try gossip.router.on_rpc(slot, frame, now_ns);
        gossip.validate_pending(now_ns);
    }

    fn validate_pending(gossip: *BlockGossip, now_ns: u64) void {
        var processed: u32 = 0;
        while (gossip.router.pop_event()) |event| : (processed += 1) {
            assert(processed < 1024);
            const verdict = gossip.check(&event, now_ns);
            switch (verdict) {
                .accept => {
                    gossip.stats.accepted += 1;
                    gossip.queue_accepted(&event.id, gossip.checked_hash);
                },
                .reject => gossip.stats.rejected += 1,
                .ignore => gossip.stats.ignored += 1,
            }
            gossip.router.validate(&event.id, switch (verdict) {
                .accept => .accept,
                .reject => .reject,
                .ignore => .ignore,
            });
        }
    }

    fn check(
        gossip: *BlockGossip,
        event: *const router_module.Event,
        now_ns: u64,
    ) validity.Acceptance {
        const data = gossip.router.message_data(&event.id) orelse return .ignore;
        const version = gossip.version_of(event.topic);
        const envelope = gossip.decode_event(version, &event.id, data) catch {
            gossip.stats.decode_failed += 1;
            return .reject;
        };
        gossip.stats.versions[@backingInt(version) - 1] += 1;
        const now_seconds = now_ns / ns_per_s;
        const result = gossip.validator.validate(&envelope, now_seconds);
        result catch |err| {
            const timestamp = envelope.payload.timestamp;
            gossip.stats.failed[@backingInt(validity.reason_of(err, timestamp, now_seconds))] += 1;
        };
        gossip.checked_hash = envelope.payload_hash;
        return validity.acceptance(result);
    }

    /// Decodes a pending message, reusing the bytes the message-id hash decompressed when
    /// `scratch` still holds them. Afterwards `scratch` holds `id`'s bytes, or nothing.
    fn decode_event(
        gossip: *BlockGossip,
        version: block.Version,
        id: *const Id,
        data: []const u8,
    ) block.DecodeError!block.Envelope {
        if (gossip.scratch_id) |held| {
            if (std.mem.eql(u8, &held, id)) {
                const bytes = gossip.scratch[0..gossip.scratch_length];
                const header = snappy.decode_header(data) catch unreachable; // Hashed valid.
                assert(header.decoded_length == bytes.len);
                gossip.stats.decompress_reused += 1;
                return block.decode_decompressed(version, bytes);
            }
        }
        gossip.scratch_id = null;
        return block.decode(version, data, gossip.scratch);
    }

    fn queue_accepted(gossip: *BlockGossip, id: *const Id, payload_hash: primitives.B256) void {
        if (gossip.accepted_count == accepted_max) {
            gossip.accepted_head = (gossip.accepted_head + 1) % accepted_max;
            gossip.accepted_count -= 1;
            gossip.stats.accepted_dropped += 1;
        }
        const tail = (gossip.accepted_head + gossip.accepted_count) % accepted_max;
        gossip.accepted[tail] = id.*;
        gossip.accepted_hashes[tail] = payload_hash;
        gossip.accepted_count += 1;
        assert(gossip.accepted_count <= accepted_max);
    }

    /// Next accepted block for consensus, decoded into `scratch` (>= 10 MiB). Blocks whose
    /// message already left the cache are skipped.
    pub fn pop_block(gossip: *BlockGossip, scratch: []u8) ?block.Envelope {
        assert(scratch.len >= snappy.gossip_size_max);
        while (gossip.accepted_count > 0) {
            const id = gossip.accepted[gossip.accepted_head];
            const payload_hash = gossip.accepted_hashes[gossip.accepted_head];
            gossip.accepted_head = (gossip.accepted_head + 1) % accepted_max;
            gossip.accepted_count -= 1;
            const entry = gossip.router.cache.find(&id) orelse continue;
            const data = gossip.router.cache.data(entry);
            const version = gossip.version_of(entry.topic);
            // Validation already decoded this exact message successfully.
            return block.decode_known_hash(version, data, scratch, payload_hash) catch
                unreachable;
        }
        return null;
    }

    pub const PublishError = block.EncodeError || Router.PublishError;

    /// Signs, compresses, and publishes a sequencer block. Returns its message id.
    pub fn publish(
        gossip: *BlockGossip,
        secret_key: [32]u8,
        parent_beacon_block_root: ?primitives.B256,
        payload: block.ExecutionPayload,
        now_ns: u64,
    ) PublishError!Id {
        const index = @backingInt(payload.version) - 1;
        const topic = gossip.topics[index];
        if (!gossip.router.is_subscribed(topic)) {
            gossip.stats.blocked_outbound[index] += 1;
            return error.NotSubscribed;
        }
        if (block.signed_length(payload) > publish_size_max) return error.TooLarge;
        const message = try block.encode_signed(
            gossip.chain_id,
            secret_key,
            parent_beacon_block_root,
            payload,
            gossip.publish_scratch,
            &gossip.compressor,
            gossip.publish_output,
        );
        // Remember our own block so echoes of it count as duplicates at this height. A
        // republish, or more blocks at one height than the table keeps, is not recorded
        // again (`insert` requires a passing `check`).
        const seen = &gossip.validator.seen;
        if (seen.check(payload.block_number, payload.block_hash)) |_| {
            seen.insert(payload.block_number, payload.block_hash);
        } else |_| {}
        const id = try gossip.router.publish(topic, message, now_ns);
        gossip.stats.published += 1;
        return id;
    }

    pub fn heartbeat(gossip: *BlockGossip, now_ns: u64) void {
        _ = gossip.retire_topics(now_ns);
        gossip.router.heartbeat(now_ns);
    }

    /// Unsubscribes block topics that can no longer carry a block inside the accepted
    /// timestamp window (base/base `retire_block_topics`). Retired topics are never
    /// rejoined, even if the clock moves backwards. Returns how many were retired.
    pub fn retire_topics(gossip: *BlockGossip, now_ns: u64) u32 {
        var retired: u32 = 0;
        for (versions, gossip.topics, 0..) |version, topic, index| {
            if (!block.is_topic_retired(gossip.validator.config, version, now_ns / ns_per_s)) {
                continue;
            }
            if (!gossip.router.unsubscribe(topic, now_ns)) continue;
            gossip.stats.retirements[index] += 1;
            retired += 1;
        }
        assert(retired <= versions.len);
        return retired;
    }
};

test {
    _ = @import("handler_test.zig");
}

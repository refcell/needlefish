//! Engine API handlers (execution-apis + OP exec-engine spec), transport agnostic.
//! `Engine(Backend)` holds the forkchoice and a bounded invalid-block cache, enforces
//! method/fork versioning and forkchoice rules, and delegates execution, storage,
//! canonicalization and payload building to `Backend`:
//!
//!   fn block(*Backend, B256) ?BlockRef
//!   fn is_ancestor(*Backend, ancestor: B256, descendant: B256) bool
//!   fn insert(*Backend, *const ExecutionPayload, *const NewPayloadParams) InsertResult
//!   fn set_forkchoice(*Backend, ForkchoiceState) EngineError!ForkchoiceApplied
//!   fn start_build(*Backend, PayloadId, parent: BlockRef, *const PayloadAttributes)
//!       EngineError!void
//!   fn built(*Backend, PayloadId) ?Backend.Built     // Built has `timestamp: u64`
//!
//! JSON encoding and JWT auth live in the RPC layer on top.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
pub const types = @import("types.zig");
pub const block = @import("block.zig");

const B256 = primitives.B256;
pub const ExecutionPayload = types.ExecutionPayload;
pub const NewPayloadParams = types.NewPayloadParams;
pub const PayloadStatus = types.PayloadStatus;
pub const ForkchoiceState = types.ForkchoiceState;
pub const ForkchoiceUpdated = types.ForkchoiceUpdated;
pub const EngineError = types.EngineError;
pub const Version = types.Version;

pub const BlockRef = struct {
    hash: B256,
    parent_hash: B256,
    number: u64,
    timestamp: u64,
};

pub const InsertResult = union(enum) {
    valid,
    invalid: []const u8,
    /// The parent state is not available (e.g. too deep a reorg); the block is not
    /// judged and stays unknown.
    syncing,
};

/// `syncing`: the backend cannot reach the head's state yet; the forkchoice is not
/// applied and no payload is built.
pub const ForkchoiceApplied = enum { applied, syncing };

pub const invalid_cache_size = 256;

pub fn Engine(comptime Backend: type) type {
    return struct {
        const Self = @This();

        spec: *const chainspec.ChainSpec,
        backend: *Backend,
        forkchoice: ?ForkchoiceState = null,
        invalid_hashes: [invalid_cache_size]B256 = undefined,
        invalid_latest_valid: [invalid_cache_size]?B256 = undefined,
        invalid_len: u32 = 0,
        invalid_next: u32 = 0,

        pub fn init(spec: *const chainspec.ChainSpec, backend: *Backend) Self {
            assert(spec.gas_limit > 0);
            return .{ .spec = spec, .backend = backend };
        }

        pub fn new_payload(
            engine: *Self,
            version: Version,
            p: *const ExecutionPayload,
            params: *const NewPayloadParams,
        ) EngineError!PayloadStatus {
            try types.validate_new_payload(engine.spec, version, p, params);
            if (engine.invalid_ancestor(p.block_hash)) |lvh| {
                return PayloadStatus.invalid(lvh, "block previously marked invalid");
            }
            if (engine.invalid_ancestor(p.parent_hash)) |lvh| {
                engine.remember_invalid(p.block_hash, lvh);
                return PayloadStatus.invalid(lvh, "links to previously rejected block");
            }
            const known = engine.backend.block(p.block_hash) != null;
            if (known) return PayloadStatus.valid(p.block_hash);
            const parent = engine.backend.block(p.parent_hash) orelse return PayloadStatus.syncing;
            assert(parent.hash.eql(p.parent_hash));
            const reason: ?[]const u8 = if (p.block_number != parent.number + 1)
                "invalid block number"
            else if (p.timestamp <= parent.timestamp)
                "timestamp not after parent"
            else
                null;
            if (reason) |r| {
                engine.remember_invalid(p.block_hash, parent.hash);
                return PayloadStatus.invalid(parent.hash, r);
            }
            switch (engine.backend.insert(p, params)) {
                .valid => return PayloadStatus.valid(p.block_hash),
                .invalid => |r| {
                    engine.remember_invalid(p.block_hash, parent.hash);
                    return PayloadStatus.invalid(parent.hash, r);
                },
                .syncing => return PayloadStatus.syncing,
            }
        }

        pub fn forkchoice_updated(
            engine: *Self,
            version: Version,
            state: ForkchoiceState,
            attributes: ?*const payload.PayloadAttributes,
        ) EngineError!ForkchoiceUpdated {
            if (state.head_block_hash.is_zero()) return error.InvalidParams;
            if (engine.invalid_ancestor(state.head_block_hash)) |lvh| {
                const status = PayloadStatus.invalid(lvh, "head previously marked invalid");
                return .{ .payload_status = status };
            }
            const head = engine.backend.block(state.head_block_hash) orelse {
                return .{ .payload_status = PayloadStatus.syncing };
            };
            try engine.check_ancestor(state.finalized_block_hash, head.hash);
            try engine.check_ancestor(state.safe_block_hash, head.hash);
            switch (try engine.backend.set_forkchoice(state)) {
                .applied => {},
                .syncing => return .{ .payload_status = PayloadStatus.syncing },
            }
            engine.forkchoice = state;
            const valid = PayloadStatus.valid(head.hash);
            const attrs = attributes orelse return .{ .payload_status = valid };
            // The forkchoice update stands even when the attributes are rejected.
            attrs.validate(engine.spec, version) catch |err| return switch (err) {
                error.UnsupportedFork => error.UnsupportedFork,
                else => error.InvalidPayloadAttributes,
            };
            if (attrs.timestamp <= head.timestamp) return error.InvalidPayloadAttributes;
            const id = switch (engine.spec.mode) {
                .l1 => attrs.payload_id_l1(head.hash),
                .l2 => attrs.payload_id(head.hash, version),
            };
            try engine.backend.start_build(id, head, attrs);
            return .{ .payload_status = valid, .payload_id = id };
        }

        pub fn get_payload(
            engine: *Self,
            version: Version,
            id: payload.PayloadId,
        ) EngineError!Backend.Built {
            const built = engine.backend.built(id) orelse return error.UnknownPayload;
            try types.validate_get_payload(engine.spec, version, built.timestamp);
            return built;
        }

        /// Zero hash means "unset" (pre-finality); otherwise it must be a known ancestor.
        fn check_ancestor(engine: *Self, ancestor: B256, head: B256) EngineError!void {
            if (ancestor.is_zero()) return;
            if (engine.backend.block(ancestor) == null) return error.InvalidForkchoiceState;
            if (!engine.backend.is_ancestor(ancestor, head)) return error.InvalidForkchoiceState;
        }

        /// The latest valid hash recorded for an invalid block, or null if not invalid.
        fn invalid_ancestor(engine: *const Self, hash: B256) ??B256 {
            for (engine.invalid_hashes[0..engine.invalid_len], 0..) |h, i| {
                if (h.eql(hash)) return engine.invalid_latest_valid[i];
            }
            return null;
        }

        fn remember_invalid(engine: *Self, hash: B256, latest_valid: ?B256) void {
            assert(engine.invalid_next < invalid_cache_size);
            engine.invalid_hashes[engine.invalid_next] = hash;
            engine.invalid_latest_valid[engine.invalid_next] = latest_valid;
            engine.invalid_next = (engine.invalid_next + 1) % invalid_cache_size;
            engine.invalid_len = @min(engine.invalid_len + 1, invalid_cache_size);
            assert(engine.invalid_len <= invalid_cache_size);
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = @import("tests.zig");
}
